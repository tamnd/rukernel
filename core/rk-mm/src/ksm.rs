//! Kernel Samepage Merging (KSM), as mm/ksm.c of Linux.
//!
//! A process marks areas of anonymous memory as mergeable with `madvise(MADV_MERGEABLE)` or with
//! `prctl(PR_SET_MEMORY_MERGE)`. The thread `ksmd` scans the pages of these areas. It maps each
//! group of pages with the same contents to one read only page, the KSM page. A write to a KSM page
//! is a fault that copies the page, as copy on write after `fork` does.
//!
//! This module has the merge logic without the page tables, so the tests on the host examine it.
//! [`Ksm`] keeps an item for each page that it scans, as the `ksm_rmap_item` of Linux. The stable
//! tree has the KSM pages. The unstable tree has the pages that did not change since the last scan
//! and that have no copy yet. A scan of a page looks for a KSM page with the same contents first,
//! and then for a page in the unstable tree. Two pages of the unstable tree with the same contents
//! become a new KSM page. The unstable tree starts empty at each full scan, as in Linux.
//!
//! The trees of Linux are red black trees that compare the contents of the pages. These trees are
//! maps from a checksum of the contents to the pages, and a merge compares all the contents first.
//! [`Pages`] gives the access to the pages and the page tables. The kernel implements it in
//! `space/ksmd.rs`, and the tests implement it with arrays.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::sync::{Once, SpinLock};

#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
pub use crate::space::ksmd::{
    exec, fork, madvise, merge_any, merging_pages, set_merge_any, stat, zero_phys,
};

/// The number of an address space in KSM. 0 is no address space.
pub type MmId = u64;

/// The size of `struct ksm_rmap_item` of Linux on a 64 bit machine. The profit of KSM takes away
/// this size for each item, as Linux does.
const RMAP_ITEM_SIZE: i64 = 64;

/// The size of a page, as a signed value for the profit.
const PAGE: i64 = crate::vma::PAGE_SIZE as i64;

/// The value of `run`: `ksmd` does not scan, and the KSM pages stay.
pub const RUN_STOP: u32 = 0;
/// The value of `run`: `ksmd` scans.
pub const RUN_MERGE: u32 = 1;
/// The value of `run`: each KSM page gets copies again, and `ksmd` does not scan.
pub const RUN_UNMERGE: u32 = 2;

/// The settings of KSM, the files of `/sys/kernel/mm/ksm` that a write changes. The defaults are
/// those of Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tunables {
    /// `run`: [`RUN_STOP`], [`RUN_MERGE`] or [`RUN_UNMERGE`].
    pub run: u32,
    /// `pages_to_scan`: the pages that `ksmd` scans before it sleeps.
    pub pages_to_scan: u32,
    /// `sleep_millisecs`: the time that `ksmd` sleeps between two batches of pages.
    pub sleep_millisecs: u32,
    /// `max_page_sharing`: the most pages that one KSM page replaces.
    pub max_page_sharing: u32,
    /// `merge_across_nodes`: pages of two NUMA nodes can merge. This kernel has one node.
    pub merge_across_nodes: bool,
    /// `use_zero_pages`: a page with only zeros maps the zero page and not a KSM page.
    pub use_zero_pages: bool,
    /// `smart_scan`: a page that did not merge in some scans is skipped in the next scans.
    pub smart_scan: bool,
    /// `stable_node_chains_prune_millisecs`. This kernel keeps no chains, so it has no effect.
    pub stable_node_chains_prune_millisecs: u32,
}

impl Default for Tunables {
    fn default() -> Self {
        Self {
            run: RUN_STOP,
            pages_to_scan: 100,
            sleep_millisecs: 20,
            max_page_sharing: 256,
            merge_across_nodes: true,
            use_zero_pages: false,
            smart_scan: true,
            stable_node_chains_prune_millisecs: 2000,
        }
    }
}

/// The counters of KSM, the files of `/sys/kernel/mm/ksm` that only a read uses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// `pages_shared`: the KSM pages.
    pub pages_shared: u64,
    /// `pages_sharing`: the pages that map a KSM page, less one for each KSM page. This is the
    /// number of pages that KSM saves.
    pub pages_sharing: u64,
    /// `pages_unshared`: the pages in the unstable tree.
    pub pages_unshared: u64,
    /// The items, `ksm_rmap_items` of Linux.
    pub rmap_items: u64,
    /// `ksm_zero_pages`: the pages that map the zero page because of `use_zero_pages`.
    pub zero_pages: u64,
    /// `full_scans`: the scans of all the mergeable pages.
    pub full_scans: u64,
    /// `pages_scanned`: the pages that `ksmd` scanned.
    pub pages_scanned: u64,
    /// `pages_skipped`: the pages that the smart scan skipped.
    pub pages_skipped: u64,
}

impl Stats {
    /// `pages_volatile`: the items that are not in a tree, because their pages change.
    pub fn pages_volatile(&self) -> u64 {
        self.rmap_items.saturating_sub(self.pages_shared + self.pages_sharing + self.pages_unshared)
    }

    /// `general_profit`: the bytes that KSM saves, less the bytes of its items.
    pub fn general_profit(&self) -> i64 {
        (self.pages_sharing + self.zero_pages) as i64 * PAGE
            - self.rmap_items as i64 * RMAP_ITEM_SIZE
    }
}

/// The counters of one address space, the lines of `/proc/PID/ksm_stat`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MmStats {
    /// `ksm_rmap_items`: the items of the address space.
    pub rmap_items: u64,
    /// `ksm_merging_pages`: the pages that map a KSM page.
    pub merging_pages: u64,
    /// `ksm_zero_pages`: the pages that map the zero page because of `use_zero_pages`.
    pub zero_pages: u64,
}

impl MmStats {
    /// `ksm_process_profit`: the bytes that KSM saves in the address space, less the bytes of its
    /// items.
    pub fn profit(&self) -> i64 {
        (self.merging_pages + self.zero_pages) as i64 * PAGE
            - self.rmap_items as i64 * RMAP_ITEM_SIZE
    }
}

/// What [`Pages::pages_of`] found in an address space.
#[derive(Clone, Debug)]
pub enum Areas {
    /// The address space does not exist now.
    Gone,
    /// The address space is busy. Its items stay for this full scan.
    Busy,
    /// The addresses of the pages in the mergeable areas that have a frame, in order.
    Pages(Vec<usize>),
}

/// What [`Pages::frame`] found at an address.
#[derive(Clone, Debug)]
pub enum Found<F> {
    /// No page is there, or the area is not mergeable now.
    None,
    /// The address space is busy. The scan tries the page again in the next full scan.
    Busy,
    /// The page has the frame `frame`. `exclusive` tells that no other mapping and no cache uses
    /// the frame, so a merge can replace it.
    Page {
        /// The frame.
        frame: F,
        /// Only this mapping uses the frame.
        exclusive: bool,
    },
}

/// The access to the pages and the page tables, for [`Ksm`].
pub trait Pages {
    /// A reference to a frame. A clone is one more reference.
    type Frame: Clone;

    /// Gives the addresses of the pages in the mergeable areas of `mm` that have a frame.
    fn pages_of(&mut self, mm: MmId) -> Areas;

    /// Gives the frame of the page at `addr` in `mm`.
    fn frame(&mut self, mm: MmId, addr: usize) -> Found<Self::Frame>;

    /// A number that is the same for two references to the same frame, such as the physical
    /// address.
    fn key(&self, frame: &Self::Frame) -> u64;

    /// A checksum of the contents of `frame`.
    fn checksum(&self, frame: &Self::Frame) -> u64;

    /// Tells if two frames have the same contents.
    fn same_contents(&self, a: &Self::Frame, b: &Self::Frame) -> bool;

    /// Tells if `frame` has only zeros.
    fn is_zero(&self, frame: &Self::Frame) -> bool;

    /// Gives the zero page, for `use_zero_pages`.
    fn zero_frame(&mut self) -> Option<Self::Frame>;

    /// Makes the page at `addr` in `mm` read only, if it still maps `frame` and only this mapping
    /// uses `frame`. Then the contents of `frame` do not change. Gives `false` if it cannot.
    fn write_protect(&mut self, mm: MmId, addr: usize, frame: &Self::Frame) -> bool;

    /// Maps `kpage` read only at `addr` in `mm` in place of `frame`. It makes the page read only
    /// first, and does the change only if the page still maps `frame`, only this mapping uses
    /// `frame` and the two frames have the same contents. Gives `false` if it did not change.
    fn replace(&mut self, mm: MmId, addr: usize, frame: &Self::Frame, kpage: &Self::Frame) -> bool;

    /// Gives the page at `addr` in `mm` a copy of `kpage` that it can write, if the page maps
    /// `kpage`. This is `break_ksm` of Linux.
    ///
    /// # Errors
    ///
    /// `ENOMEM` if no frame is free for the copy.
    fn unshare(&mut self, mm: MmId, addr: usize, kpage: &Self::Frame) -> Result<(), Errno>;
}

/// Where an item is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// In no tree: the page is new, it changed since the last scan or it cannot merge.
    Volatile,
    /// In the unstable tree. The tree of the scan `round` has it.
    Unstable { round: u64 },
    /// The page maps the KSM page of the stable node with this number.
    Stable(u64),
    /// The page maps the zero page.
    Zero,
}

/// The data of one scanned page, `struct ksm_rmap_item` of Linux.
#[derive(Clone, Copy, Debug)]
struct Item {
    state: State,
    /// The checksum of the contents at the last scan, or `None` before the first one.
    checksum: Option<u64>,
    /// The last full scan that found the page.
    round: u64,
    /// The scans since the page changed, for the smart scan.
    age: u8,
    /// The scans that the smart scan skips before it scans the page again.
    skips: u8,
}

/// A KSM page and the number of pages that map it, `struct ksm_stable_node` of Linux.
#[derive(Clone, Debug)]
struct StableNode<F> {
    frame: F,
    key: u64,
    checksum: u64,
    members: u64,
}

/// The position of the scan.
#[derive(Clone, Debug, Default)]
struct Cursor {
    /// The index in `mms` of the next address space.
    next: usize,
    /// The address space of `pages`.
    mm: MmId,
    /// The pages of `mm` to scan in this full scan.
    pages: Vec<usize>,
    /// The index in `pages` of the next page.
    pos: usize,
}

/// The state of KSM: the items, the trees and the counters.
#[derive(Debug)]
pub struct Ksm<F> {
    /// The address spaces with mergeable areas, in the order of the scan.
    mms: Vec<MmId>,
    items: BTreeMap<(MmId, usize), Item>,
    stable: BTreeMap<u64, StableNode<F>>,
    /// The stable nodes by the checksum of their contents.
    stable_by_sum: BTreeMap<u64, Vec<u64>>,
    /// The stable nodes by the key of their frames.
    stable_by_key: BTreeMap<u64, u64>,
    /// The unstable tree of this full scan.
    unstable: BTreeMap<u64, Vec<(MmId, usize)>>,
    next_node: u64,
    /// The number of this full scan.
    round: u64,
    cursor: Cursor,
    per_mm: BTreeMap<MmId, MmStats>,
    stats: Stats,
    /// The pages that map a KSM page.
    members: u64,
}

impl<F: Clone> Default for Ksm<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Clone> Ksm<F> {
    /// Makes an empty state.
    pub const fn new() -> Self {
        Self {
            mms: Vec::new(),
            items: BTreeMap::new(),
            stable: BTreeMap::new(),
            stable_by_sum: BTreeMap::new(),
            stable_by_key: BTreeMap::new(),
            unstable: BTreeMap::new(),
            next_node: 1,
            round: 1,
            cursor: Cursor { next: 0, mm: 0, pages: Vec::new(), pos: 0 },
            per_mm: BTreeMap::new(),
            stats: Stats {
                pages_shared: 0,
                pages_sharing: 0,
                pages_unshared: 0,
                rmap_items: 0,
                zero_pages: 0,
                full_scans: 0,
                pages_scanned: 0,
                pages_skipped: 0,
            },
            members: 0,
        }
    }

    /// The counters.
    pub fn stats(&self) -> Stats {
        Stats { pages_sharing: self.members - self.stats.pages_shared, ..self.stats }
    }

    /// The counters of the address space `mm`.
    pub fn mm_stats(&self, mm: MmId) -> MmStats {
        self.per_mm.get(&mm).copied().unwrap_or_default()
    }

    /// Tells if an address space is in the scan.
    pub fn has_mms(&self) -> bool {
        !self.mms.is_empty()
    }

    /// Adds the address space `mm` to the scan, `__ksm_enter` of Linux.
    pub fn add_mm(&mut self, mm: MmId) {
        if !self.mms.contains(&mm) {
            self.mms.push(mm);
        }
    }

    /// Removes the address space `mm` and its items, as Linux does when a process ends. The pages
    /// of `mm` go away with its page table.
    pub fn remove_mm(&mut self, mm: MmId) {
        if let Some(i) = self.mms.iter().position(|&m| m == mm) {
            self.mms.remove(i);
            if i < self.cursor.next {
                self.cursor.next -= 1;
            }
        }
        if self.cursor.mm == mm {
            self.cursor.pages.clear();
            self.cursor.pos = 0;
        }
        self.remove_items(mm, 0, usize::MAX);
        self.per_mm.remove(&mm);
    }

    /// Removes the items of `mm` in `start..end`.
    fn remove_items(&mut self, mm: MmId, start: usize, end: usize) {
        let keys: Vec<(MmId, usize)> =
            self.items.range((mm, start)..(mm, end)).map(|(&k, _)| k).collect();
        for key in keys {
            self.remove_item(key);
        }
    }

    fn remove_item(&mut self, key: (MmId, usize)) {
        let Some(mut item) = self.items.remove(&key) else { return };
        self.leave(key.0, &mut item);
        self.stats.rmap_items -= 1;
        if let Some(m) = self.per_mm.get_mut(&key.0) {
            m.rmap_items -= 1;
        }
    }

    /// Takes the item out of its tree. It is then volatile.
    fn leave(&mut self, mm: MmId, item: &mut Item) {
        match item.state {
            State::Volatile => {}
            State::Unstable { .. } => self.stats.pages_unshared -= 1,
            State::Stable(id) => {
                self.members -= 1;
                if let Some(m) = self.per_mm.get_mut(&mm) {
                    m.merging_pages -= 1;
                }
                let empty = self.stable.get_mut(&id).is_some_and(|node| {
                    node.members -= 1;
                    node.members == 0
                });
                if empty {
                    self.remove_node(id);
                }
            }
            State::Zero => {
                self.stats.zero_pages -= 1;
                if let Some(m) = self.per_mm.get_mut(&mm) {
                    m.zero_pages -= 1;
                }
            }
        }
        item.state = State::Volatile;
    }

    fn remove_node(&mut self, id: u64) {
        let Some(node) = self.stable.remove(&id) else { return };
        self.stats.pages_shared -= 1;
        self.stable_by_key.remove(&node.key);
        if let Some(ids) = self.stable_by_sum.get_mut(&node.checksum) {
            ids.retain(|&i| i != id);
            if ids.is_empty() {
                self.stable_by_sum.remove(&node.checksum);
            }
        }
    }

    /// Puts the item in the stable node `id`.
    fn join(&mut self, mm: MmId, item: &mut Item, id: u64) {
        if let Some(node) = self.stable.get_mut(&id) {
            node.members += 1;
            self.members += 1;
            self.per_mm.entry(mm).or_default().merging_pages += 1;
            item.state = State::Stable(id);
            item.age = 0;
        }
    }

    /// Makes a stable node for the KSM page `frame`, and gives its number.
    fn new_node(&mut self, frame: F, key: u64, checksum: u64) -> u64 {
        let id = self.next_node;
        self.next_node += 1;
        self.stable.insert(id, StableNode { frame, key, checksum, members: 0 });
        self.stable_by_sum.entry(checksum).or_default().push(id);
        self.stable_by_key.insert(key, id);
        self.stats.pages_shared += 1;
        id
    }

    /// Scans up to `n` pages, `ksm_do_scan` of Linux. Gives `true` if a full scan ended. The scan
    /// stops at the end of a full scan, as in Linux.
    pub fn scan<P: Pages<Frame = F>>(&mut self, p: &mut P, tun: &Tunables, mut n: usize) -> bool {
        while n > 0 {
            if self.cursor.pos < self.cursor.pages.len() {
                let addr = self.cursor.pages[self.cursor.pos];
                self.cursor.pos += 1;
                self.scan_page(p, tun, self.cursor.mm, addr);
                n -= 1;
                continue;
            }
            if self.mms.is_empty() {
                return true;
            }
            if self.cursor.next >= self.mms.len() {
                self.end_round();
                return true;
            }
            let mm = self.mms[self.cursor.next];
            self.cursor.next += 1;
            match p.pages_of(mm) {
                Areas::Pages(pages) => {
                    self.cursor = Cursor { mm, pages, pos: 0, next: self.cursor.next };
                }
                Areas::Busy => {
                    let round = self.round;
                    for (_, item) in self.items.range_mut((mm, 0)..=(mm, usize::MAX)) {
                        item.round = round;
                    }
                }
                Areas::Gone => self.remove_mm(mm),
            }
        }
        false
    }

    /// Ends a full scan. The items of the pages that the scan did not find go away, and the
    /// unstable tree starts again.
    fn end_round(&mut self) {
        let round = self.round;
        let stale: Vec<(MmId, usize)> =
            self.items.iter().filter(|(_, i)| i.round != round).map(|(&k, _)| k).collect();
        for key in stale {
            self.remove_item(key);
        }
        self.unstable.clear();
        self.round += 1;
        self.stats.full_scans += 1;
        self.cursor = Cursor::default();
    }

    /// Tells if the smart scan skips the item now, `should_skip_rmap_item` of Linux.
    fn skip(item: &mut Item) -> bool {
        let age = item.age;
        item.age = item.age.saturating_add(1);
        if age < 3 {
            return false;
        }
        if item.skips > 0 {
            item.skips -= 1;
            return true;
        }
        item.skips = match age {
            0..=4 => 2,
            5..=7 => 4,
            _ => 8,
        };
        false
    }

    /// Scans the page at `addr` of `mm`, `cmp_and_merge_page` of Linux.
    pub fn scan_page<P: Pages<Frame = F>>(
        &mut self,
        p: &mut P,
        tun: &Tunables,
        mm: MmId,
        addr: usize,
    ) {
        self.stats.pages_scanned += 1;
        let key = (mm, addr);
        let (frame, exclusive) = match p.frame(mm, addr) {
            Found::Page { frame, exclusive } => (frame, exclusive),
            Found::Busy => {
                if let Some(item) = self.items.get_mut(&key) {
                    item.round = self.round;
                }
                return;
            }
            Found::None => {
                self.remove_item(key);
                return;
            }
        };
        // The fast path: the page maps the KSM page of its item still.
        if let Some(&id) = self.stable_by_key.get(&p.key(&frame))
            && let Some(item) = self.items.get_mut(&key)
            && item.state == State::Stable(id)
        {
            item.round = self.round;
            return;
        }
        let mut item = match self.items.remove(&key) {
            Some(item) => item,
            None => {
                self.stats.rmap_items += 1;
                self.per_mm.entry(mm).or_default().rmap_items += 1;
                Item { state: State::Volatile, checksum: None, round: 0, age: 0, skips: 0 }
            }
        };
        item.round = self.round;
        if self.merge(p, tun, mm, addr, frame, exclusive, &mut item) {
            self.items.insert(key, item);
        } else {
            self.items.insert(key, item);
            self.remove_item(key);
        }
    }

    /// Does the work of `scan_page` for an item that is out of the map. Gives `false` if the item
    /// goes away.
    #[allow(clippy::too_many_arguments)]
    fn merge<P: Pages<Frame = F>>(
        &mut self,
        p: &mut P,
        tun: &Tunables,
        mm: MmId,
        addr: usize,
        frame: F,
        exclusive: bool,
        item: &mut Item,
    ) -> bool {
        let fkey = p.key(&frame);
        // The page maps a KSM page already. A page of a child of `fork` joins the node here.
        if let Some(&id) = self.stable_by_key.get(&fkey) {
            if item.state != State::Stable(id) {
                self.leave(mm, item);
                self.join(mm, item, id);
            }
            return true;
        }
        // A page that maps the zero page after a read is not anonymous memory, and KSM does not
        // keep an item for it. A page that KSM mapped to the zero page keeps its item.
        if p.zero_frame().is_some_and(|z| p.key(&z) == fkey) {
            return item.state == State::Zero;
        }
        // The page is not a KSM page now, so a write copied it.
        self.leave(mm, item);
        if tun.smart_scan && Self::skip(item) {
            self.stats.pages_skipped += 1;
            self.stats.pages_scanned -= 1;
            return true;
        }
        let sum = p.checksum(&frame);
        // Look for a KSM page with the same contents.
        if exclusive && let Some(id) = self.stable_match(p, tun, &frame, sum) {
            let kpage = self.stable[&id].frame.clone();
            if p.replace(mm, addr, &frame, &kpage) {
                self.join(mm, item, id);
                item.checksum = Some(sum);
            }
            return true;
        }
        // A page that changes often does not go in the unstable tree.
        if item.checksum != Some(sum) {
            item.checksum = Some(sum);
            item.age = 0;
            return true;
        }
        if !exclusive {
            return true;
        }
        if tun.use_zero_pages
            && p.is_zero(&frame)
            && let Some(z) = p.zero_frame()
        {
            if p.replace(mm, addr, &frame, &z) {
                item.state = State::Zero;
                self.stats.zero_pages += 1;
                self.per_mm.entry(mm).or_default().zero_pages += 1;
            }
            return true;
        }
        // Look for a page with the same contents in the unstable tree.
        let round = self.round;
        let candidates = self.unstable.get(&sum).cloned().unwrap_or_default();
        // With one candidate, `replace` does the only compare. This saves a read of two pages.
        let compare = candidates.len() > 1;
        for other in candidates {
            if other == (mm, addr)
                || !self.items.get(&other).is_some_and(|i| i.state == State::Unstable { round })
            {
                continue;
            }
            let Found::Page { frame: of, exclusive: true } = p.frame(other.0, other.1) else {
                continue;
            };
            if (compare && !p.same_contents(&frame, &of)) || !p.write_protect(other.0, other.1, &of)
            {
                continue;
            }
            // The other page is read only now, so its contents are fixed. `replace` compares
            // them again with the contents of this page.
            if !p.replace(mm, addr, &frame, &of) {
                continue;
            }
            let okey = p.key(&of);
            let id = self.new_node(of, okey, sum);
            if let Some(mut o) = self.items.remove(&other) {
                self.leave(other.0, &mut o);
                self.join(other.0, &mut o, id);
                self.items.insert(other, o);
            }
            self.join(mm, item, id);
            if let Some(list) = self.unstable.get_mut(&sum) {
                list.retain(|&k| k != other);
            }
            return true;
        }
        self.unstable.entry(sum).or_default().push((mm, addr));
        item.state = State::Unstable { round };
        self.stats.pages_unshared += 1;
        true
    }

    /// Finds a KSM page with the same contents as `frame` that can take one more page.
    fn stable_match<P: Pages<Frame = F>>(
        &self,
        p: &P,
        tun: &Tunables,
        frame: &F,
        sum: u64,
    ) -> Option<u64> {
        let ids = self.stable_by_sum.get(&sum)?;
        let room = |id: &u64| self.stable[id].members < u64::from(tun.max_page_sharing);
        // With one node, `replace` does the only compare. This saves a read of two pages.
        if let [id] = ids.as_slice() {
            return room(id).then_some(*id);
        }
        // The last node is the one that most likely has room.
        ids.iter()
            .rev()
            .copied()
            .find(|id| room(id) && p.same_contents(frame, &self.stable[id].frame))
    }

    /// Gives each page of `mm` in `start..end` that maps a KSM page or the zero page a copy, and
    /// removes the items of the range. `MADV_UNMERGEABLE` uses it.
    ///
    /// # Errors
    ///
    /// `ENOMEM` if no frame is free for a copy. The items of the pages that did not get a copy
    /// stay.
    pub fn unmerge_range<P: Pages<Frame = F>>(
        &mut self,
        p: &mut P,
        mm: MmId,
        start: usize,
        end: usize,
    ) -> Result<(), Errno> {
        let keys: Vec<(MmId, usize)> =
            self.items.range((mm, start)..(mm, end)).map(|(&k, _)| k).collect();
        for key in keys {
            let kpage = match self.items[&key].state {
                State::Stable(id) => self.stable.get(&id).map(|n| n.frame.clone()),
                State::Zero => p.zero_frame(),
                _ => None,
            };
            if let Some(kpage) = kpage {
                p.unshare(key.0, key.1, &kpage)?;
            }
            self.remove_item(key);
        }
        Ok(())
    }

    /// Gives each page that maps a KSM page a copy, and removes all the items, as a write of 2
    /// to `run` does. The address spaces stay in the scan.
    ///
    /// # Errors
    ///
    /// `ENOMEM` if no frame is free for a copy.
    pub fn unmerge_all<P: Pages<Frame = F>>(&mut self, p: &mut P) -> Result<(), Errno> {
        let mms: Vec<MmId> = self.per_mm.keys().copied().collect();
        for mm in mms {
            self.unmerge_range(p, mm, 0, usize::MAX)?;
        }
        self.unstable.clear();
        self.cursor = Cursor::default();
        Ok(())
    }
}

/// The settings and a copy of the counters of KSM, for the files of `/sys/kernel/mm/ksm`.
#[derive(Clone, Copy, Debug)]
pub struct Control {
    /// The settings.
    pub tun: Tunables,
    /// The counters at the last change.
    pub stats: Stats,
}

/// The settings and the counters of KSM. `ksmd` reads the settings and copies the counters here
/// after each page.
pub static CONTROL: SpinLock<Control> = SpinLock::new(Control {
    tun: Tunables {
        run: RUN_STOP,
        pages_to_scan: 100,
        sleep_millisecs: 20,
        max_page_sharing: 256,
        merge_across_nodes: true,
        use_zero_pages: false,
        smart_scan: true,
        stable_node_chains_prune_millisecs: 2000,
    },
    stats: Stats {
        pages_shared: 0,
        pages_sharing: 0,
        pages_unshared: 0,
        rmap_items: 0,
        zero_pages: 0,
        full_scans: 0,
        pages_scanned: 0,
        pages_skipped: 0,
    },
});

/// The work of a change of a setting that the kernel does.
#[derive(Clone, Copy, Debug)]
pub struct Hooks {
    /// Gives each page that maps a KSM page a copy, for a write of 2 to `run`.
    pub unmerge_all: fn() -> Result<(), Errno>,
    /// Wakes `ksmd`, after a change of a setting.
    pub wake: fn(),
}

static HOOKS: Once<Hooks> = Once::new();

/// Sets the hooks. The kernel calls it when the first address space gets mergeable areas. Before
/// that, no page can be a KSM page and `ksmd` does not run, so no hook is necessary.
pub fn set_hooks(hooks: Hooks) {
    HOOKS.call_once(|| hooks);
}

/// The files of `/sys/kernel/mm/ksm`, and if a write can change them.
pub const FILES: [(&str, bool); 17] = [
    ("full_scans", false),
    ("general_profit", false),
    ("ksm_zero_pages", false),
    ("max_page_sharing", true),
    ("merge_across_nodes", true),
    ("pages_scanned", false),
    ("pages_shared", false),
    ("pages_sharing", false),
    ("pages_skipped", false),
    ("pages_to_scan", true),
    ("pages_unshared", false),
    ("pages_volatile", false),
    ("run", true),
    ("sleep_millisecs", true),
    ("smart_scan", true),
    ("stable_node_chains", false),
    ("stable_node_chains_prune_millisecs", true),
];

/// Gives the text of the file `name` of `/sys/kernel/mm/ksm`, as Linux. `stable_node_dups` and
/// `stable_node_chains` are 0, because this kernel makes a new KSM page and not a chain when a KSM
/// page has `max_page_sharing` pages.
pub fn show(c: &Control, name: &str) -> Option<String> {
    let (t, s) = (&c.tun, &c.stats);
    let text = match name {
        "full_scans" => format!("{}", s.full_scans),
        "general_profit" => format!("{}", s.general_profit()),
        "ksm_zero_pages" => format!("{}", s.zero_pages),
        "max_page_sharing" => format!("{}", t.max_page_sharing),
        "merge_across_nodes" => format!("{}", u8::from(t.merge_across_nodes)),
        "pages_scanned" => format!("{}", s.pages_scanned),
        "pages_shared" => format!("{}", s.pages_shared),
        "pages_sharing" => format!("{}", s.pages_sharing),
        "pages_skipped" => format!("{}", s.pages_skipped),
        "pages_to_scan" => format!("{}", t.pages_to_scan),
        "pages_unshared" => format!("{}", s.pages_unshared),
        "pages_volatile" => format!("{}", s.pages_volatile()),
        "run" => format!("{}", t.run),
        "sleep_millisecs" => format!("{}", t.sleep_millisecs),
        "smart_scan" => format!("{}", u8::from(t.smart_scan)),
        "stable_node_chains" | "stable_node_dups" => String::from("0"),
        "stable_node_chains_prune_millisecs" => format!("{}", t.stable_node_chains_prune_millisecs),
        "use_zero_pages" => format!("{}", u8::from(t.use_zero_pages)),
        _ => return None,
    };
    Some(text + "\n")
}

/// Parses an unsigned decimal number as `kstrtouint` of Linux: an optional `+`, the digits and
/// an optional newline at the end.
fn parse_uint(data: &[u8]) -> Option<u32> {
    let data = data.strip_suffix(b"\n").unwrap_or(data);
    let data = data.strip_prefix(b"+").unwrap_or(data);
    if data.is_empty() || !data.iter().all(u8::is_ascii_digit) {
        return None;
    }
    core::str::from_utf8(data).ok()?.parse().ok()
}

/// Parses a boolean as `kstrtobool` of Linux.
fn parse_bool(data: &[u8]) -> Option<bool> {
    match data {
        [b'y' | b'Y' | b'1', ..] => Some(true),
        [b'n' | b'N' | b'0', ..] => Some(false),
        [b'o' | b'O', b'n' | b'N', ..] => Some(true),
        [b'o' | b'O', b'f' | b'F', ..] => Some(false),
        _ => None,
    }
}

/// What the kernel does after a write to a file of `/sys/kernel/mm/ksm`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum After {
    /// Nothing.
    Nothing,
    /// Wake `ksmd`.
    Wake,
    /// Give each page that maps a KSM page a copy.
    Unmerge,
}

/// Changes the settings in `c` for a write of `data` to the file `name` of `/sys/kernel/mm/ksm`,
/// with the checks of mm/ksm.c of Linux, and tells what the kernel does next.
///
/// # Errors
///
/// `EINVAL` for a bad value, `EBUSY` for a change of `max_page_sharing` or `merge_across_nodes`
/// while KSM pages exist, and `EACCES` for a file that a write cannot change.
pub fn store(c: &mut Control, name: &str, data: &[u8]) -> Result<After, Errno> {
    let t = &mut c.tun;
    let uint = || parse_uint(data).ok_or(Errno::EINVAL);
    let boolean = || parse_bool(data).ok_or(Errno::EINVAL);
    match name {
        "run" => {
            let run = uint()?;
            if run > RUN_UNMERGE {
                return Err(Errno::EINVAL);
            }
            let old = t.run;
            t.run = run;
            if run == RUN_UNMERGE && old != RUN_UNMERGE {
                return Ok(After::Unmerge);
            }
        }
        "pages_to_scan" => t.pages_to_scan = uint()?,
        "sleep_millisecs" => t.sleep_millisecs = uint()?,
        "max_page_sharing" => {
            let knob = i32::try_from(uint()?).map_err(|_| Errno::EINVAL)?;
            if knob < 2 {
                return Err(Errno::EINVAL);
            }
            if knob as u32 != t.max_page_sharing {
                if c.stats.pages_shared != 0 {
                    return Err(Errno::EBUSY);
                }
                t.max_page_sharing = knob as u32;
            }
        }
        "merge_across_nodes" => {
            let knob = uint()?;
            if knob > 1 {
                return Err(Errno::EINVAL);
            }
            if (knob == 1) != t.merge_across_nodes {
                if c.stats.pages_shared != 0 {
                    return Err(Errno::EBUSY);
                }
                t.merge_across_nodes = knob == 1;
            }
        }
        "use_zero_pages" => t.use_zero_pages = boolean()?,
        "smart_scan" => t.smart_scan = boolean()?,
        "stable_node_chains_prune_millisecs" => t.stable_node_chains_prune_millisecs = uint()?,
        _ => return Err(Errno::EACCES),
    }
    Ok(After::Wake)
}

/// Gives the files of `/sys/kernel/mm/ksm` with their text, and if a write can change them.
pub fn sysfs_files() -> Vec<(&'static str, String, bool)> {
    let c = *CONTROL.lock();
    let mut out: Vec<(&'static str, String, bool)> = FILES
        .iter()
        .chain(&[("stable_node_dups", false), ("use_zero_pages", true)])
        .map(|&(n, w)| (n, show(&c, n).unwrap_or_default(), w))
        .collect();
    out.sort_by_key(|f| f.0);
    out
}

/// Writes `data` to the file `name` of `/sys/kernel/mm/ksm`. A write of 2 to `run` gives each page
/// that maps a KSM page a copy before it returns, as in Linux.
///
/// # Errors
///
/// As [`store`], and `ENOMEM` if no frame is free for a copy.
pub fn sysfs_store(name: &str, data: &[u8]) -> Result<(), Errno> {
    let after = store(&mut CONTROL.lock(), name, data)?;
    let Some(hooks) = HOOKS.get() else { return Ok(()) };
    match after {
        After::Nothing => {}
        After::Wake => (hooks.wake)(),
        After::Unmerge => (hooks.unmerge_all)()?,
    }
    Ok(())
}

/// The text of `/proc/PID/ksm_stat`, as `proc_pid_ksm_stat` of Linux.
pub fn stat_text(s: &MmStats, merge_any: bool, mergeable: bool) -> String {
    let yes = |b: bool| if b { "yes" } else { "no" };
    format!(
        "ksm_rmap_items {}\nksm_zero_pages {}\nksm_merging_pages {}\nksm_process_profit {}\n\
         ksm_merge_any: {}\nksm_mergeable: {}\n",
        s.rmap_items,
        s.zero_pages,
        s.merging_pages,
        s.profit(),
        yes(merge_any),
        yes(mergeable)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Pages in arrays. A frame is an index in `frames`, and a page table maps an address to a
    /// frame. The number of references of a frame is the number of page tables that map it, and
    /// one more for each KSM page.
    #[derive(Default)]
    struct Fake {
        frames: Vec<Vec<u8>>,
        tables: BTreeMap<MmId, BTreeMap<usize, (usize, bool)>>,
        /// Frames that a cache or another mapping also uses.
        pinned: Vec<usize>,
        zero: Option<usize>,
        busy: Option<MmId>,
    }

    impl Fake {
        fn alloc(&mut self, fill: u8) -> usize {
            self.frames.push(vec![fill; 8]);
            self.frames.len() - 1
        }

        fn map(&mut self, mm: MmId, addr: usize, fill: u8) {
            let f = self.alloc(fill);
            self.tables.entry(mm).or_default().insert(addr, (f, true));
        }

        fn mappers(&self, f: usize) -> usize {
            self.tables.values().flat_map(|t| t.values()).filter(|(g, _)| *g == f).count()
        }

        fn at(&self, mm: MmId, addr: usize) -> (usize, bool) {
            self.tables[&mm][&addr]
        }

        /// A write of the user, with copy on write for a read only page.
        fn write(&mut self, mm: MmId, addr: usize, fill: u8) {
            let (f, writable) = self.at(mm, addr);
            if writable {
                self.frames[f].fill(fill);
                return;
            }
            let g = self.alloc(fill);
            self.tables.get_mut(&mm).unwrap().insert(addr, (g, true));
        }
    }

    impl Pages for Fake {
        type Frame = usize;

        fn pages_of(&mut self, mm: MmId) -> Areas {
            if self.busy == Some(mm) {
                return Areas::Busy;
            }
            match self.tables.get(&mm) {
                Some(t) => Areas::Pages(t.keys().copied().collect()),
                None => Areas::Gone,
            }
        }

        fn frame(&mut self, mm: MmId, addr: usize) -> Found<usize> {
            if self.busy == Some(mm) {
                return Found::Busy;
            }
            match self.tables.get(&mm).and_then(|t| t.get(&addr)) {
                Some(&(f, _)) => Found::Page {
                    frame: f,
                    exclusive: self.mappers(f) == 1 && !self.pinned.contains(&f),
                },
                None => Found::None,
            }
        }

        fn key(&self, frame: &usize) -> u64 {
            *frame as u64
        }

        fn checksum(&self, frame: &usize) -> u64 {
            self.frames[*frame].iter().fold(7, |h, &b| h * 31 + u64::from(b))
        }

        fn same_contents(&self, a: &usize, b: &usize) -> bool {
            self.frames[*a] == self.frames[*b]
        }

        fn is_zero(&self, frame: &usize) -> bool {
            self.frames[*frame].iter().all(|&b| b == 0)
        }

        fn zero_frame(&mut self) -> Option<usize> {
            if self.zero.is_none() {
                self.zero = Some(self.alloc(0));
            }
            self.zero
        }

        fn write_protect(&mut self, mm: MmId, addr: usize, frame: &usize) -> bool {
            let ok = self.at(mm, addr).0 == *frame && self.mappers(*frame) == 1;
            if ok {
                self.tables.get_mut(&mm).unwrap().insert(addr, (*frame, false));
            }
            ok
        }

        fn replace(&mut self, mm: MmId, addr: usize, frame: &usize, kpage: &usize) -> bool {
            if !self.write_protect(mm, addr, frame) || !self.same_contents(frame, kpage) {
                return false;
            }
            self.tables.get_mut(&mm).unwrap().insert(addr, (*kpage, false));
            true
        }

        fn unshare(&mut self, mm: MmId, addr: usize, kpage: &usize) -> Result<(), Errno> {
            if self.at(mm, addr).0 == *kpage {
                let data = self.frames[*kpage].clone();
                self.frames.push(data);
                let g = self.frames.len() - 1;
                self.tables.get_mut(&mm).unwrap().insert(addr, (g, true));
            }
            Ok(())
        }
    }

    fn tun() -> Tunables {
        Tunables { run: RUN_MERGE, smart_scan: false, ..Tunables::default() }
    }

    /// Runs `n` full scans.
    fn full_scans(k: &mut Ksm<usize>, p: &mut Fake, t: &Tunables, n: u64) {
        let end = k.stats().full_scans + n;
        while k.stats().full_scans < end {
            k.scan(p, t, 1000);
        }
    }

    /// Three address spaces with 4 pages each, as `create_same_memory` of LTP does it.
    fn three(fills: [u8; 3]) -> (Ksm<usize>, Fake) {
        let mut p = Fake::default();
        let mut k = Ksm::new();
        for (mm, &fill) in (1..).zip(&fills) {
            for i in 0..4 {
                p.map(mm, i * 4096, fill);
            }
            k.add_mm(mm);
        }
        (k, p)
    }

    fn counts(k: &Ksm<usize>) -> (u64, u64, u64, u64) {
        let s = k.stats();
        (s.pages_shared, s.pages_sharing, s.pages_unshared, s.pages_volatile())
    }

    #[test]
    fn equal_pages_merge_after_two_scans() {
        let (mut k, mut p) = three(*b"caa");
        let t = tun();
        full_scans(&mut k, &mut p, &t, 1);
        assert_eq!(counts(&k), (0, 0, 0, 12), "the first scan takes the checksums");
        full_scans(&mut k, &mut p, &t, 1);
        assert_eq!(counts(&k), (2, 10, 0, 0));
        let c = p.at(1, 0).0;
        assert!((0..4).all(|i| p.at(1, i * 4096) == (c, false)), "one read only KSM page");
        assert_eq!(p.at(2, 0).0, p.at(3, 4096).0);
        assert_ne!(p.at(2, 0).0, c);
        assert_eq!(k.mm_stats(1), MmStats { rmap_items: 4, merging_pages: 4, zero_pages: 0 });
        full_scans(&mut k, &mut p, &t, 3);
        assert_eq!(counts(&k), (2, 10, 0, 0), "more scans change nothing");
    }

    #[test]
    fn a_write_copies_the_page_and_the_scan_merges_it_again() {
        let (mut k, mut p) = three(*b"caa");
        let t = tun();
        full_scans(&mut k, &mut p, &t, 2);
        let a = p.at(2, 0).0;
        // The second address space writes `b` to all its pages, as the second step of ksm01.
        for i in 0..4 {
            p.write(2, i * 4096, b'b');
        }
        assert_eq!(p.frames[a], vec![b'a'; 8], "the KSM page does not change");
        assert_ne!(p.at(2, 0).0, a);
        assert!(p.at(2, 0).1, "the copy is writable");
        full_scans(&mut k, &mut p, &t, 3);
        assert_eq!(counts(&k), (3, 9, 0, 0));
        assert_eq!(p.at(3, 0).0, a, "the third address space keeps the KSM page");
    }

    #[test]
    fn a_unique_page_stays_in_the_unstable_tree() {
        let (mut k, mut p) = three(*b"ddd");
        p.write(2, 3 * 4096, b'e');
        let t = tun();
        full_scans(&mut k, &mut p, &t, 3);
        assert_eq!(counts(&k), (1, 10, 1, 0));
        assert!(p.at(2, 3 * 4096).1, "the unique page stays writable");
    }

    #[test]
    fn a_page_that_changes_is_volatile() {
        let (mut k, mut p) = three(*b"xyz");
        let t = tun();
        full_scans(&mut k, &mut p, &t, 1);
        p.write(1, 0, b'q');
        full_scans(&mut k, &mut p, &t, 1);
        // The pages of each space are equal, so each space has a KSM page of its own.
        assert_eq!(counts(&k), (3, 8, 0, 1));
    }

    #[test]
    fn unmerge_all_gives_copies_and_removes_the_items() {
        let (mut k, mut p) = three(*b"caa");
        let t = tun();
        full_scans(&mut k, &mut p, &t, 2);
        k.unmerge_all(&mut p).unwrap();
        assert_eq!(k.stats().rmap_items, 0);
        assert_eq!(counts(&k), (0, 0, 0, 0));
        let mut frames: Vec<usize> =
            p.tables.values().flat_map(|t| t.values().map(|v| v.0)).collect();
        frames.sort_unstable();
        frames.dedup();
        assert_eq!(frames.len(), 12, "each page has its own frame");
        assert!(p.tables.values().flat_map(|t| t.values()).all(|v| v.1));
        assert!((0..4).all(|i| p.frames[p.at(1, i * 4096).0] == vec![b'c'; 8]));
        full_scans(&mut k, &mut p, &t, 2);
        assert_eq!(counts(&k), (2, 10, 0, 0), "a new scan merges again");
    }

    #[test]
    fn unmerge_range_copies_only_the_range() {
        let (mut k, mut p) = three(*b"ccc");
        let t = tun();
        full_scans(&mut k, &mut p, &t, 2);
        k.unmerge_range(&mut p, 1, 0, 2 * 4096).unwrap();
        assert_eq!(k.mm_stats(1).rmap_items, 2);
        assert_eq!(k.mm_stats(1).merging_pages, 2);
        assert!(p.at(1, 0).1 && p.at(1, 4096).1);
        assert!(!p.at(1, 2 * 4096).1);
        assert_eq!(counts(&k), (1, 9, 0, 0));
    }

    #[test]
    fn max_page_sharing_makes_a_second_ksm_page() {
        let (mut k, mut p) = three(*b"ccc");
        let t = Tunables { max_page_sharing: 8, ..tun() };
        full_scans(&mut k, &mut p, &t, 3);
        assert_eq!(counts(&k), (2, 10, 0, 0));
    }

    #[test]
    fn a_shared_page_does_not_merge() {
        let (mut k, mut p) = three(*b"cab");
        let shared = p.at(1, 0).0;
        p.pinned.push(shared);
        let t = tun();
        full_scans(&mut k, &mut p, &t, 3);
        assert_eq!(p.at(1, 0), (shared, true));
        assert_eq!(counts(&k), (3, 8, 0, 1));
    }

    #[test]
    fn the_scan_forgets_a_page_that_goes_away_and_an_exited_space() {
        let (mut k, mut p) = three(*b"ccc");
        let t = tun();
        full_scans(&mut k, &mut p, &t, 2);
        p.tables.get_mut(&1).unwrap().remove(&0);
        p.tables.remove(&3);
        full_scans(&mut k, &mut p, &t, 1);
        assert_eq!(k.stats().rmap_items, 7);
        assert_eq!(counts(&k), (1, 6, 0, 0));
        assert_eq!(k.mm_stats(3), MmStats::default());
        k.remove_mm(2);
        assert_eq!(counts(&k), (1, 2, 0, 0));
        assert_eq!(k.stats().rmap_items, 3);
    }

    #[test]
    fn a_child_of_fork_joins_the_ksm_page() {
        let (mut k, mut p) = three(*b"ccc");
        let t = tun();
        full_scans(&mut k, &mut p, &t, 2);
        let child = p.tables[&1].clone();
        p.tables.insert(4, child);
        k.add_mm(4);
        full_scans(&mut k, &mut p, &t, 1);
        assert_eq!(counts(&k), (1, 15, 0, 0));
        assert_eq!(k.mm_stats(4).merging_pages, 4);
    }

    #[test]
    fn a_busy_space_keeps_its_items() {
        let (mut k, mut p) = three(*b"ccc");
        let t = tun();
        full_scans(&mut k, &mut p, &t, 2);
        p.busy = Some(2);
        full_scans(&mut k, &mut p, &t, 2);
        assert_eq!(counts(&k), (1, 11, 0, 0));
    }

    #[test]
    fn zero_pages_map_the_zero_page() {
        let (mut k, mut p) = three([0, 0, b'a']);
        let t = Tunables { use_zero_pages: true, ..tun() };
        full_scans(&mut k, &mut p, &t, 2);
        let s = k.stats();
        assert_eq!((s.zero_pages, s.pages_shared, s.pages_sharing), (8, 1, 3));
        assert_eq!(k.mm_stats(1).zero_pages, 4);
        assert_eq!(p.at(1, 0).0, p.zero.unwrap());
        k.unmerge_all(&mut p).unwrap();
        assert_ne!(p.at(1, 0).0, p.zero.unwrap());
        assert_eq!(k.stats().zero_pages, 0);
    }

    #[test]
    fn smart_scan_skips_a_page_that_does_not_merge() {
        let mut p = Fake::default();
        let mut k = Ksm::new();
        p.map(1, 0, b'a');
        k.add_mm(1);
        let t = Tunables { smart_scan: true, ..tun() };
        full_scans(&mut k, &mut p, &t, 30);
        let s = k.stats();
        assert_eq!(s.pages_skipped, 22, "{s:?}");
        assert_eq!(s.pages_skipped + s.pages_scanned, 30);
    }

    #[test]
    fn the_files_show_the_values_of_linux() {
        let mut c = Control { tun: Tunables::default(), stats: Stats::default() };
        assert_eq!(show(&c, "run").as_deref(), Some("0\n"));
        assert_eq!(show(&c, "pages_to_scan").as_deref(), Some("100\n"));
        assert_eq!(show(&c, "sleep_millisecs").as_deref(), Some("20\n"));
        assert_eq!(show(&c, "max_page_sharing").as_deref(), Some("256\n"));
        assert_eq!(show(&c, "smart_scan").as_deref(), Some("1\n"));
        c.stats = Stats { pages_shared: 2, pages_sharing: 10, rmap_items: 13, ..Stats::default() };
        assert_eq!(show(&c, "pages_volatile").as_deref(), Some("1\n"));
        assert_eq!(show(&c, "general_profit").as_deref(), Some("40128\n"));
        assert_eq!(show(&c, "nothing"), None);
    }

    #[test]
    fn a_write_checks_the_value_as_linux() {
        let mut c = Control { tun: Tunables::default(), stats: Stats::default() };
        assert_eq!(store(&mut c, "run", b"1\n"), Ok(After::Wake));
        assert_eq!(c.tun.run, 1);
        assert_eq!(store(&mut c, "run", b"3"), Err(Errno::EINVAL));
        assert_eq!(store(&mut c, "run", b"2"), Ok(After::Unmerge));
        assert_eq!(store(&mut c, "pages_to_scan", b"+98304\n"), Ok(After::Wake));
        assert_eq!(c.tun.pages_to_scan, 98304);
        assert_eq!(store(&mut c, "sleep_millisecs", b"-1"), Err(Errno::EINVAL));
        assert_eq!(store(&mut c, "max_page_sharing", b"1"), Err(Errno::EINVAL));
        assert_eq!(store(&mut c, "smart_scan", b"n"), Ok(After::Wake));
        assert!(!c.tun.smart_scan);
        assert_eq!(store(&mut c, "use_zero_pages", b"x"), Err(Errno::EINVAL));
        assert_eq!(store(&mut c, "pages_shared", b"1"), Err(Errno::EACCES));
        c.stats.pages_shared = 1;
        assert_eq!(store(&mut c, "max_page_sharing", b"300"), Err(Errno::EBUSY));
        assert_eq!(store(&mut c, "max_page_sharing", b"256"), Ok(After::Wake));
        assert_eq!(store(&mut c, "merge_across_nodes", b"0"), Err(Errno::EBUSY));
        c.stats.pages_shared = 0;
        assert_eq!(store(&mut c, "merge_across_nodes", b"0"), Ok(After::Wake));
        assert_eq!(store(&mut c, "merge_across_nodes", b"2"), Err(Errno::EINVAL));
    }

    #[test]
    fn the_stat_file_has_the_lines_of_linux() {
        let s = MmStats { rmap_items: 4, merging_pages: 3, zero_pages: 0 };
        assert_eq!(
            stat_text(&s, false, true),
            "ksm_rmap_items 4\nksm_zero_pages 0\nksm_merging_pages 3\nksm_process_profit \
             12032\nksm_merge_any: no\nksm_mergeable: yes\n"
        );
    }
}

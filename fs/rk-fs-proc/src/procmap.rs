//! The `PROCMAP_QUERY` ioctl of `/proc/PID/maps`, and the entries of `/proc/PID/pagemap` and
//! `/proc/kpageflags`, as fs/proc/task_mmu.c and fs/proc/page.c of Linux.
//!
//! This module has the parts without the state of the kernel: the layout of
//! `struct procmap_query`, the search for the area of a query and the bits of the entries.

use rk_abi::Errno;

/// `PROCMAP_QUERY`: `_IOWR('f', 17, struct procmap_query)`.
pub(crate) const PROCMAP_QUERY: u32 = 0xC068_6611;

/// The size of `struct procmap_query`.
pub(crate) const QUERY_SIZE: usize = 104;

/// The end of the field `query_addr`. A smaller `size` is an error.
const QUERY_MIN_SIZE: u64 = 24;

/// `PROCMAP_QUERY_VMA_READABLE`.
pub(crate) const VMA_READABLE: u64 = 0x01;
/// `PROCMAP_QUERY_VMA_WRITABLE`.
pub(crate) const VMA_WRITABLE: u64 = 0x02;
/// `PROCMAP_QUERY_VMA_EXECUTABLE`.
pub(crate) const VMA_EXECUTABLE: u64 = 0x04;
/// `PROCMAP_QUERY_VMA_SHARED`.
pub(crate) const VMA_SHARED: u64 = 0x08;
/// `PROCMAP_QUERY_COVERING_OR_NEXT_VMA`: the area at the address, or else the next area.
const COVERING_OR_NEXT_VMA: u64 = 0x10;
/// `PROCMAP_QUERY_FILE_BACKED_VMA`: only an area of a file.
const FILE_BACKED_VMA: u64 = 0x20;
/// The flags that a query can have.
const VALID_FLAGS: u64 = 0x3f;

/// The present bit of an entry of `/proc/PID/pagemap`, `PM_PRESENT` of Linux.
pub(crate) const PM_PRESENT: u64 = 1 << 63;
/// The bit of an entry of `/proc/PID/pagemap` for a page of a file or of shared memory,
/// `PM_FILE` of Linux.
pub(crate) const PM_FILE: u64 = 1 << 61;
/// The bits of the page frame number in an entry of `/proc/PID/pagemap`.
pub(crate) const PM_PFN_MASK: u64 = (1 << 55) - 1;
/// The bit of an entry of `/proc/PID/pagemap` for a page that a write changed after the last
/// write of 4 to `/proc/PID/clear_refs`, `PM_SOFT_DIRTY` of Linux.
pub(crate) const PM_SOFT_DIRTY: u64 = 1 << 55;
/// The bit of an entry of `/proc/PID/pagemap` for a page that only one mapping maps,
/// `PM_MMAP_EXCLUSIVE` of Linux.
pub(crate) const PM_MMAP_EXCLUSIVE: u64 = 1 << 56;

/// `KPF_UPTODATE` of `/proc/kpageflags`.
pub(crate) const KPF_UPTODATE: u64 = 1 << 3;
/// `KPF_DIRTY` of `/proc/kpageflags`.
pub(crate) const KPF_DIRTY: u64 = 1 << 4;
/// `KPF_LRU` of `/proc/kpageflags`.
pub(crate) const KPF_LRU: u64 = 1 << 5;
/// `KPF_MMAP` of `/proc/kpageflags`.
pub(crate) const KPF_MMAP: u64 = 1 << 11;
/// `KPF_ANON` of `/proc/kpageflags`.
pub(crate) const KPF_ANON: u64 = 1 << 12;
/// `KPF_SWAPBACKED` of `/proc/kpageflags`.
pub(crate) const KPF_SWAPBACKED: u64 = 1 << 14;
/// `KPF_COMPOUND_HEAD` of `/proc/kpageflags`: the first page of a huge page.
pub(crate) const KPF_COMPOUND_HEAD: u64 = 1 << 15;
/// `KPF_COMPOUND_TAIL` of `/proc/kpageflags`: a page of a huge page after the first.
pub(crate) const KPF_COMPOUND_TAIL: u64 = 1 << 16;
/// `KPF_HUGE` of `/proc/kpageflags`: a page of hugetlbfs.
pub(crate) const KPF_HUGE: u64 = 1 << 17;
/// `KPF_KSM` of `/proc/kpageflags`: a page that KSM merged.
pub(crate) const KPF_KSM: u64 = 1 << 21;
/// `KPF_THP` of `/proc/kpageflags`: a page of a transparent huge page.
pub(crate) const KPF_THP: u64 = 1 << 22;
/// `KPF_ZERO_PAGE` of `/proc/kpageflags`: the page of zeros.
pub(crate) const KPF_ZERO_PAGE: u64 = 1 << 24;
/// `KPF_RESERVED` of `/proc/kpageflags`, a flag of the kernel that `PG_reserved` gives.
pub(crate) const KPF_RESERVED: u64 = 1 << 32;

/// The flags of a mapped page of a file in `/proc/kpageflags`. `KPF_DIRTY` comes in addition when
/// a mapping changed the page after the last write back.
pub(crate) const KPF_FILE_PAGE: u64 = KPF_UPTODATE | KPF_LRU | KPF_MMAP;
/// The flags of an anonymous page of a process in `/proc/kpageflags`, as `stable_page_flags` in
/// fs/proc/page.c of Linux gives them for a page that `do_anonymous_page` or a copy on write
/// made. The dirty state of such a page is in the page table, so `KPF_DIRTY` is not there.
pub(crate) const KPF_ANON_PAGE: u64 = KPF_FILE_PAGE | KPF_ANON | KPF_SWAPBACKED;

/// The kind of a huge page that a frame is a part of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Compound {
    /// A transparent huge page.
    Thp,
    /// A page of hugetlbfs that a mapping or a file uses.
    Hugetlb,
    /// A page of hugetlbfs that is free in the pool.
    HugetlbFree,
}

/// The facts about a frame that give its entry of `/proc/kpageflags`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct FrameFacts {
    /// The frame is the page of zeros of KSM.
    pub zero: bool,
    /// The frame holds anonymous memory of a process.
    pub anon: bool,
    /// KSM merged the frame.
    pub ksm: bool,
    /// The frame is the copy of a page of a mapped file, and the page is dirty or not.
    pub file: Option<bool>,
    /// The frame is a part of a huge page of the kind, and it is the first page or not.
    pub huge: Option<(Compound, bool)>,
}

/// The entry of `/proc/kpageflags` of a frame, as `stable_page_flags` in fs/proc/page.c of Linux
/// gives it for the same page.
pub(crate) fn page_flags(f: &FrameFacts) -> u64 {
    if f.zero {
        return KPF_ZERO_PAGE | KPF_RESERVED;
    }
    let part = |head: bool| if head { KPF_COMPOUND_HEAD } else { KPF_COMPOUND_TAIL };
    match f.huge {
        // A free page of the pool has only the flags of its compound page.
        Some((Compound::HugetlbFree, head)) => return KPF_HUGE | part(head),
        // A page of hugetlbfs is not on the LRU lists and is not swap backed. A page of a file
        // is dirty, as `hugetlb_add_to_page_cache` of Linux marks it.
        Some((Compound::Hugetlb, head)) => {
            let kind = if f.anon { KPF_ANON } else { KPF_DIRTY };
            return KPF_UPTODATE | KPF_MMAP | KPF_HUGE | part(head) | kind;
        }
        _ => {}
    }
    let mut u = if f.anon {
        // A KSM page is dirty, as `try_to_merge_one_page` of Linux marks it.
        KPF_ANON_PAGE | if f.ksm { KPF_KSM | KPF_DIRTY } else { 0 }
    } else {
        match f.file {
            Some(true) => KPF_FILE_PAGE | KPF_DIRTY,
            Some(false) => KPF_FILE_PAGE,
            None => return 0,
        }
    };
    if let Some((Compound::Thp, head)) = f.huge {
        u |= KPF_THP | part(head);
    }
    u
}

/// The facts about a page of a process that give its entry of `/proc/PID/pagemap`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PageFacts {
    /// The page has a frame.
    pub present: bool,
    /// The page frame number, if the caller can see it.
    pub pfn: Option<u64>,
    /// The frame is the page of zeros, which `vm_normal_page` of Linux does not give.
    pub zero: bool,
    /// The frame is not anonymous memory.
    pub file: bool,
    /// Only this mapping maps the frame.
    pub exclusive: bool,
    /// The page is soft-dirty.
    pub soft_dirty: bool,
}

/// The entry of `/proc/PID/pagemap` of a page, as `pte_to_pagemap_entry` in fs/proc/task_mmu.c of
/// Linux.
pub(crate) fn pagemap_entry(p: &PageFacts) -> u64 {
    let mut entry = if p.soft_dirty { PM_SOFT_DIRTY } else { 0 };
    if !p.present {
        return entry;
    }
    entry |= PM_PRESENT | p.pfn.map_or(0, |pfn| pfn & PM_PFN_MASK);
    // The page of zeros is not a normal page, so it has no file bit and no exclusive bit.
    if !p.zero {
        if p.file {
            entry |= PM_FILE;
        }
        if p.exclusive {
            entry |= PM_MMAP_EXCLUSIVE;
        }
    }
    entry
}

/// What a write to `/proc/PID/clear_refs` does, as `clear_refs_write` in fs/proc/task_mmu.c of
/// Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClearRefs {
    /// 1, 2 and 3 clear the referenced bits, which this kernel does not keep.
    Referenced,
    /// 4 makes all the pages clean in the soft-dirty state.
    SoftDirty,
    /// 5 sets the high water mark of the resident pages to the resident pages now.
    Hiwater,
}

/// Parses the number that a write to `/proc/PID/clear_refs` gives, as `kstrtoint` of Linux after
/// `strstrip`.
///
/// # Errors
///
/// `EINVAL` for a value that is not a number from 1 to 5.
pub(crate) fn parse_clear_refs(data: &[u8]) -> Result<ClearRefs, Errno> {
    let text = core::str::from_utf8(data).map_err(|_| Errno::EINVAL)?;
    match text.trim().parse::<i32>().map_err(|_| Errno::EINVAL)? {
        1..=3 => Ok(ClearRefs::Referenced),
        4 => Ok(ClearRefs::SoftDirty),
        5 => Ok(ClearRefs::Hiwater),
        _ => Err(Errno::EINVAL),
    }
}

/// The fields of an area that a query looks at.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Area {
    /// The first address.
    pub start: u64,
    /// The address after the last byte.
    pub end: u64,
    /// The `VMA_*` flags of the area.
    pub flags: u64,
    /// The area maps a file.
    pub file: bool,
}

/// The input fields of `struct procmap_query`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Query {
    /// `size`: the size of the structure that the caller knows.
    pub size: u64,
    /// `query_flags`.
    pub flags: u64,
    /// `query_addr`.
    pub addr: u64,
    /// `vma_name_size`: the size of the buffer for the name.
    pub name_size: u32,
    /// `build_id_size`: the size of the buffer for the build ID.
    pub build_id_size: u32,
    /// `vma_name_addr`.
    pub name_addr: u64,
    /// `build_id_addr`.
    pub build_id_addr: u64,
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[at..at + 8]);
    u64::from_ne_bytes(v)
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    let mut v = [0u8; 4];
    v.copy_from_slice(&b[at..at + 4]);
    u32::from_ne_bytes(v)
}

impl Query {
    /// Reads the input fields from the first `QUERY_SIZE` bytes of the structure, as
    /// `do_procmap_query` of Linux. `raw` has zeros after the `size` bytes of the caller.
    ///
    /// # Errors
    ///
    /// `EINVAL` for a size that does not have `query_addr`, for an unknown flag, and for a name
    /// or build ID buffer with a size and no address, or with an address and no size.
    pub(crate) fn parse(raw: &[u8; QUERY_SIZE]) -> Result<Self, Errno> {
        let q = Self {
            size: u64_at(raw, 0),
            flags: u64_at(raw, 8),
            addr: u64_at(raw, 16),
            name_size: u32_at(raw, 80),
            build_id_size: u32_at(raw, 84),
            name_addr: u64_at(raw, 88),
            build_id_addr: u64_at(raw, 96),
        };
        if q.size < QUERY_MIN_SIZE
            || q.flags & !VALID_FLAGS != 0
            || (q.name_size != 0) != (q.name_addr != 0)
            || (q.build_id_size != 0) != (q.build_id_addr != 0)
        {
            return Err(Errno::EINVAL);
        }
        Ok(q)
    }
}

/// The output fields of `struct procmap_query`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Answer {
    /// `vma_start`.
    pub start: u64,
    /// `vma_end`.
    pub end: u64,
    /// `vma_flags`.
    pub flags: u64,
    /// `vma_page_size`.
    pub page_size: u64,
    /// `vma_offset`.
    pub offset: u64,
    /// `inode`.
    pub inode: u64,
    /// `dev_major`.
    pub major: u32,
    /// `dev_minor`.
    pub minor: u32,
    /// `vma_name_size`: the length of the name with its zero byte, or 0 for no name.
    pub name_size: u32,
}

/// Gives the structure of the answer to `q`: the input fields of `q` and the fields of `a`.
pub(crate) fn encode(q: &Query, a: &Answer) -> [u8; QUERY_SIZE] {
    let mut out = [0u8; QUERY_SIZE];
    let mut put = |at: usize, b: &[u8]| out[at..at + b.len()].copy_from_slice(b);
    put(0, &q.size.to_ne_bytes());
    put(8, &q.flags.to_ne_bytes());
    put(16, &q.addr.to_ne_bytes());
    put(24, &a.start.to_ne_bytes());
    put(32, &a.end.to_ne_bytes());
    put(40, &a.flags.to_ne_bytes());
    put(48, &a.page_size.to_ne_bytes());
    put(56, &a.offset.to_ne_bytes());
    put(64, &a.inode.to_ne_bytes());
    put(72, &a.major.to_ne_bytes());
    put(76, &a.minor.to_ne_bytes());
    put(80, &a.name_size.to_ne_bytes());
    // No build ID: `build_id_size` is 0.
    put(88, &q.name_addr.to_ne_bytes());
    put(96, &q.build_id_addr.to_ne_bytes());
    out
}

/// Finds the area for the query `q` in `areas`, which are in the order of their addresses, as
/// `query_matching_vma` of Linux. Gives the index of the area.
///
/// # Errors
///
/// `ENOENT` if no area matches.
pub(crate) fn find(areas: &[Area], q: &Query) -> Result<usize, Errno> {
    let next = q.flags & COVERING_OR_NEXT_VMA != 0;
    let mut addr = q.addr;
    loop {
        // The first area that ends after the address, as `find_vma`.
        let i = areas.partition_point(|a| a.end <= addr);
        let a = areas.get(i).ok_or(Errno::ENOENT)?;
        if !next && a.start > addr {
            return Err(Errno::ENOENT);
        }
        let want = q.flags & (VMA_READABLE | VMA_WRITABLE | VMA_EXECUTABLE | VMA_SHARED);
        let file_ok = q.flags & FILE_BACKED_VMA == 0 || a.file;
        if a.flags & want == want && file_ok {
            return Ok(i);
        }
        // The area does not match. Only `COVERING_OR_NEXT_VMA` looks at the next area.
        if !next {
            return Err(Errno::ENOENT);
        }
        addr = a.end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn area(start: u64, end: u64, flags: u64, file: bool) -> Area {
        Area { start, end, flags, file }
    }

    fn query(addr: u64, flags: u64) -> Query {
        Query { size: QUERY_SIZE as u64, flags, addr, ..Query::default() }
    }

    #[test]
    fn page_flags_match_linux() {
        // The bits of include/uapi/linux/kernel-page-flags.h of Linux.
        assert_eq!(KPF_ANON_PAGE, 0x5828);
        assert_eq!(KPF_FILE_PAGE | KPF_DIRTY, 0x838);
        assert_eq!(KPF_COMPOUND_HEAD | KPF_COMPOUND_TAIL | KPF_HUGE, 0x3_8000);
        assert_eq!(KPF_KSM | KPF_THP | KPF_ZERO_PAGE, 0x160_0000);
        assert_eq!(PM_SOFT_DIRTY | PM_MMAP_EXCLUSIVE, 0x0180_0000_0000_0000);
    }

    #[test]
    fn page_flags_as_linux() {
        let anon = FrameFacts { anon: true, ..FrameFacts::default() };
        assert_eq!(page_flags(&FrameFacts::default()), 0);
        assert_eq!(page_flags(&anon), 0x5828);
        assert_eq!(page_flags(&FrameFacts { ksm: true, ..anon }), 0x20_5838);
        let zero = FrameFacts { zero: true, ..FrameFacts::default() };
        assert_eq!(page_flags(&zero), (1 << 32) | (1 << 24));
        let file = FrameFacts { file: Some(true), ..FrameFacts::default() };
        assert_eq!(page_flags(&file), 0x838);
        let thp = FrameFacts { huge: Some((Compound::Thp, true)), ..anon };
        assert_eq!(page_flags(&thp), 0x40_d828);
        let tail = FrameFacts { huge: Some((Compound::Thp, false)), ..anon };
        assert_eq!(page_flags(&tail), 0x41_5828);
        let huge = FrameFacts { huge: Some((Compound::Hugetlb, true)), ..anon };
        assert_eq!(page_flags(&huge), 0x2_9808);
        let shared = FrameFacts { huge: Some((Compound::Hugetlb, false)), ..FrameFacts::default() };
        assert_eq!(page_flags(&shared), 0x3_0818);
        let free =
            FrameFacts { huge: Some((Compound::HugetlbFree, true)), ..FrameFacts::default() };
        assert_eq!(page_flags(&free), 0x2_8000);
    }

    #[test]
    fn pagemap_entry_as_linux() {
        assert_eq!(pagemap_entry(&PageFacts::default()), 0);
        let hole = PageFacts { soft_dirty: true, ..PageFacts::default() };
        assert_eq!(pagemap_entry(&hole), PM_SOFT_DIRTY);
        let anon = PageFacts { present: true, pfn: Some(0x1234), exclusive: true, ..hole };
        assert_eq!(pagemap_entry(&anon), PM_PRESENT | PM_SOFT_DIRTY | PM_MMAP_EXCLUSIVE | 0x1234);
        let file = PageFacts { present: true, file: true, ..PageFacts::default() };
        assert_eq!(pagemap_entry(&file), PM_PRESENT | PM_FILE);
        let zero = PageFacts { zero: true, exclusive: true, ..file };
        assert_eq!(pagemap_entry(&zero), PM_PRESENT);
    }

    #[test]
    fn clear_refs_values() {
        assert_eq!(parse_clear_refs(b"4\n"), Ok(ClearRefs::SoftDirty));
        assert_eq!(parse_clear_refs(b"1"), Ok(ClearRefs::Referenced));
        assert_eq!(parse_clear_refs(b"5"), Ok(ClearRefs::Hiwater));
        assert_eq!(parse_clear_refs(b"6"), Err(Errno::EINVAL));
        assert_eq!(parse_clear_refs(b"0"), Err(Errno::EINVAL));
        assert_eq!(parse_clear_refs(b"x"), Err(Errno::EINVAL));
    }

    #[test]
    fn find_matches_as_linux() {
        let areas = [
            area(0x1000, 0x2000, VMA_READABLE, true),
            area(0x2000, 0x3000, VMA_READABLE | VMA_EXECUTABLE, true),
            area(0x5000, 0x6000, VMA_READABLE | VMA_WRITABLE, false),
        ];
        assert_eq!(find(&areas, &query(0x1000, 0)), Ok(0));
        assert_eq!(find(&areas, &query(0x2fff, 0)), Ok(1));
        assert_eq!(find(&areas, &query(0xfff, 0)), Err(Errno::ENOENT));
        assert_eq!(find(&areas, &query(0xfff, COVERING_OR_NEXT_VMA)), Ok(0));
        assert_eq!(find(&areas, &query(0x1000, VMA_WRITABLE)), Err(Errno::ENOENT));
        let q = query(0x1000, VMA_WRITABLE | COVERING_OR_NEXT_VMA);
        assert_eq!(find(&areas, &q), Ok(2));
        let q = query(0x1000, FILE_BACKED_VMA | VMA_EXECUTABLE | COVERING_OR_NEXT_VMA);
        assert_eq!(find(&areas, &q), Ok(1));
        assert_eq!(find(&areas, &query(0x6000, COVERING_OR_NEXT_VMA)), Err(Errno::ENOENT));
    }

    #[test]
    fn parse_checks_the_fields() {
        let mut raw = [0u8; QUERY_SIZE];
        raw[..8].copy_from_slice(&(QUERY_SIZE as u64).to_ne_bytes());
        raw[16..24].copy_from_slice(&0x1234u64.to_ne_bytes());
        let q = Query::parse(&raw).unwrap();
        assert_eq!((q.size, q.addr), (QUERY_SIZE as u64, 0x1234));
        let mut bad = raw;
        bad[..8].copy_from_slice(&16u64.to_ne_bytes());
        assert_eq!(Query::parse(&bad), Err(Errno::EINVAL));
        let mut bad = raw;
        bad[8..16].copy_from_slice(&0x40u64.to_ne_bytes());
        assert_eq!(Query::parse(&bad), Err(Errno::EINVAL));
        let mut bad = raw;
        bad[80..84].copy_from_slice(&16u32.to_ne_bytes());
        assert_eq!(Query::parse(&bad), Err(Errno::EINVAL));
    }

    #[test]
    fn encode_puts_the_fields_at_their_offsets() {
        let q = Query { size: 104, flags: 1, addr: 2, name_addr: 9, ..Query::default() };
        let a = Answer {
            start: 3,
            end: 4,
            flags: 5,
            page_size: 4096,
            offset: 6,
            inode: 7,
            major: 8,
            minor: 10,
            name_size: 11,
        };
        let out = encode(&q, &a);
        assert_eq!(u64_at(&out, 24), 3);
        assert_eq!(u64_at(&out, 48), 4096);
        assert_eq!(u32_at(&out, 76), 10);
        assert_eq!(u32_at(&out, 80), 11);
        assert_eq!(u32_at(&out, 84), 0);
        assert_eq!(u64_at(&out, 88), 9);
    }
}

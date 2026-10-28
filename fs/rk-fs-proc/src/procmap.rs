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

/// `KPF_UPTODATE` of `/proc/kpageflags`.
pub(crate) const KPF_UPTODATE: u64 = 1 << 3;
/// `KPF_DIRTY` of `/proc/kpageflags`.
pub(crate) const KPF_DIRTY: u64 = 1 << 4;
/// `KPF_LRU` of `/proc/kpageflags`.
pub(crate) const KPF_LRU: u64 = 1 << 5;
/// `KPF_MMAP` of `/proc/kpageflags`.
pub(crate) const KPF_MMAP: u64 = 1 << 11;

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
